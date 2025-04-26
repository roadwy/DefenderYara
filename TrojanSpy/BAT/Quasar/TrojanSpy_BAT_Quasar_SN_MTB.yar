
rule TrojanSpy_BAT_Quasar_SN_MTB{
	meta:
		description = "TrojanSpy:BAT/Quasar.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 1d 5d 16 fe 01 13 04 11 04 2c 0b 07 09 07 09 91 1f 4d 61 b4 9c 00 00 09 17 d6 0d 09 08 31 e0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}