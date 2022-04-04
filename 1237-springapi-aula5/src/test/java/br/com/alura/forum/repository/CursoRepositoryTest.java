package br.com.alura.forum.repository;

import br.com.alura.forum.modelo.Curso;
import org.junit.Assert;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.jupiter.api.Assertions.*;

@RunWith(SpringRunner.class)
@DataJpaTest
@AutoConfigureTestDatabase( replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("test")
public class CursoRepositoryTest {

    //injeção de dependencias
    @Autowired
    private CursoRepository repository;

    @Autowired
    private TestEntityManager em;

    @Test
    public void deveriaCarrefarUmCursoAoBuscarPeloSeuNome(){
        String nomeCurso = "HTML 5";
       Curso html5 = new Curso();
       html5.setNome(nomeCurso);
       html5.setCategoria("Programacao");
       em.persist(html5);

        Curso curso = repository.findByNome(nomeCurso);
        // assert serve de comparativa como se fosse um .equals
        Assert.assertNotNull(curso);
        // verifica se é igual o que veio no objeto curso e o nome curos.
        Assert.assertEquals(nomeCurso,curso.getNome());

    }
    @Test
    public void naoDeveriaCarrefarUmCursoAoBuscarPeloSeuNome(){
        String nomeCurso = "JPA";
        Curso curso = repository.findByNome(nomeCurso);
        // assert serve de comparativa como se fosse um .equals
        Assert.assertNull(curso);
        // verifica se é igual o que veio no objeto curso e o nome curos.
    }

}
