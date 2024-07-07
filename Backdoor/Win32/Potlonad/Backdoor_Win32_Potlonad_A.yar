
rule Backdoor_Win32_Potlonad_A{
	meta:
		description = "Backdoor:Win32/Potlonad.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 62 6f 74 73 2e 70 68 70 3f 6e 61 6d 65 3d } //1 /bots.php?name=
		$a_01_1 = {50 61 74 6f 44 6f 6e 61 6c 64 28 24 46 75 65 67 6f 5b 31 5d 29 3b } //1 PatoDonald($Fuego[1]);
		$a_01_2 = {24 46 75 65 67 6f 20 3d 20 40 65 78 70 6c 6f 64 65 28 22 42 6f 74 4a 61 76 61 22 20 2c 20 24 4d 69 43 61 6c 69 66 69 63 61 63 69 6f 6e 29 20 3b } //1 $Fuego = @explode("BotJava" , $MiCalificacion) ;
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}