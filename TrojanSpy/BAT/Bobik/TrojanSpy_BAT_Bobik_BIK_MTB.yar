
rule TrojanSpy_BAT_Bobik_BIK_MTB{
	meta:
		description = "TrojanSpy:BAT/Bobik.BIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 92 03 00 70 0a 06 28 ?? ?? ?? 0a 0b 07 6f ?? ?? ?? 0a 0c 08 6f } //2
		$a_01_1 = {66 00 72 00 65 00 65 00 67 00 65 00 6f 00 69 00 70 00 2e 00 61 00 70 00 70 00 2f 00 78 00 6d 00 6c 00 } //1 freegeoip.app/xml
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}