
rule Backdoor_BAT_Chopper_EX_dha{
	meta:
		description = "Backdoor:BAT/Chopper.EX!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e 00 2f 00 61 00 75 00 74 00 68 00 2f 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 2f 00 74 00 68 00 65 00 6d 00 65 00 73 00 2f 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2f 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2e 00 61 00 73 00 70 00 78 00 } //1 ~/auth/Current/themes/resources/resources.aspx
		$a_01_1 = {66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 20 00 78 00 6f 00 72 00 28 00 72 00 61 00 77 00 53 00 74 00 72 00 3a 00 53 00 74 00 72 00 69 00 6e 00 67 00 2c 00 6b 00 65 00 79 00 3a 00 53 00 74 00 72 00 69 00 6e 00 67 00 29 00 3a 00 53 00 74 00 72 00 69 00 6e 00 67 00 7b 00 } //1 function xor(rawStr:String,key:String):String{
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}