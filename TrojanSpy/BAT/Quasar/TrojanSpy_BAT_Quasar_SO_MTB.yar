
rule TrojanSpy_BAT_Quasar_SO_MTB{
	meta:
		description = "TrojanSpy:BAT/Quasar.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 3b 00 00 0a 72 4d 00 00 70 73 3c 00 00 0a 28 3d 00 00 0a 6f 3e 00 00 0a 0c dd 06 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}