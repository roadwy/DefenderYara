
rule Trojan_Win32_Emotet_DDY_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 08 6a 01 53 53 8d [0-03] 51 ff 15 ?? ?? ?? ?? 85 c0 75 ?? 6a 08 6a 01 53 53 8d [0-03] 52 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b [0-03] 8d [0-03] 50 53 53 68 34 01 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}