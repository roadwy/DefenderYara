
rule Trojan_Win32_Glupteba_FQ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.FQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 d8 85 40 00 58 09 fe 81 ef ?? ?? ?? ?? e8 ?? ?? ?? ?? 01 f6 46 31 01 29 f7 47 41 39 d9 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}