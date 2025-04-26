
rule TrojanSpy_Win32_Bancos_QS{
	meta:
		description = "TrojanSpy:Win32/Bancos.QS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 0a 8b c6 8b 55 f8 e8 ?? ?? ?? ?? 4b 85 db 0f 85 8c f6 ff ff } //1
		$a_01_1 = {50 72 6f 6a 65 63 74 32 2e 64 6c 6c 00 53 68 6f 77 46 6f 72 6d 00 } //1 牐橯捥㉴搮汬匀潨䙷牯m
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}