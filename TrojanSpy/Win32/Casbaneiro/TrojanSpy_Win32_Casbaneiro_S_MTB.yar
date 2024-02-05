
rule TrojanSpy_Win32_Casbaneiro_S_MTB{
	meta:
		description = "TrojanSpy:Win32/Casbaneiro.S!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c0 55 68 c8 42 61 00 64 ff 30 64 89 20 8b 45 fc e8 be fc ff ff 33 c0 5a 59 59 64 89 10 eb 15 e9 9f 58 df ff 8b 55 fc 8b 45 fc e8 d0 00 00 00 e8 ab 5d df ff 8b 45 fc 80 b8 bc 00 00 00 00 74 bf } //00 00 
	condition:
		any of ($a_*)
 
}