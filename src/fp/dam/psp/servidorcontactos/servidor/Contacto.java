package fp.dam.psp.servidorcontactos.servidor;

public class Contacto {
    private String nombre;
    private int num;

    public Contacto(String nombre, int num) {
        this.nombre = nombre;
        this.num = num;
    }

    public int getNum() {
        return num;
    }

    public void setNum(int num) {
        this.num = num;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    @Override
    public String toString() {
        return "Contacto{" +
                "nombre='" + nombre + '\'' +
                ", num=" + num +
                '}';
    }
}
