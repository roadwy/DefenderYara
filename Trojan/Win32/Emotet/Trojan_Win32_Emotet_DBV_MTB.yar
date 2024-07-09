
rule Trojan_Win32_Emotet_DBV_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 0c b0 03 cb e8 ?? ?? ?? ?? 35 ?? ?? ?? ?? 3b 45 fc 74 12 8b 45 f8 46 3b 77 18 72 e3 } //1
		$a_00_1 = {8b 16 8d 49 04 33 55 f4 8d 76 04 88 51 fc 8b c2 c1 e8 08 47 c1 ea 10 88 41 fd 88 51 fe c1 ea 08 88 51 ff 3b fb 72 d9 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}