
rule Trojan_Win32_Injuke_SACF_MTB{
	meta:
		description = "Trojan:Win32/Injuke.SACF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c0 83 c9 ff 31 d2 f2 ae 0f be 83 ?? ?? ?? ?? f7 d1 49 89 44 24 04 89 d8 f7 f1 0f be 84 15 ?? ?? ?? ?? 89 04 24 e8 ?? ?? ?? ?? 88 04 1e 43 81 fb } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}