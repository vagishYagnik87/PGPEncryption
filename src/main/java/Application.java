import controller.BaseController;

public class Application {

    /**
     * This is tester function which is run locally
     * @param args
     */
    public static void main(String[] args) {
        try {
            BaseController.INSTANCE.encrypt();
            BaseController.INSTANCE.decrypt();
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.exit(0);
    }

}
