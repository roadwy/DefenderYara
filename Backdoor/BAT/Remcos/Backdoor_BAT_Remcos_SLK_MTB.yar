
rule Backdoor_BAT_Remcos_SLK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 02 05 06 6f 8a 00 00 0a 0b 03 6f 8b 00 00 0a 19 58 04 fe 02 16 fe 01 0c 08 2c 0c } //2
		$a_81_1 = {46 4d 61 6e 61 67 65 72 41 70 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 FManagerApp.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}