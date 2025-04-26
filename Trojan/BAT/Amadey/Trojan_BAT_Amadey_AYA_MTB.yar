
rule Trojan_BAT_Amadey_AYA_MTB{
	meta:
		description = "Trojan:BAT/Amadey.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 33 39 61 39 32 37 37 66 2d 33 63 63 38 2d 34 34 38 38 2d 61 35 61 32 2d 66 38 66 38 66 31 34 32 32 63 37 35 } //3 $39a9277f-3cc8-4488-a5a2-f8f8f1422c75
		$a_01_1 = {6f 76 72 66 6c 77 2e 65 78 65 } //2 ovrflw.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}