
rule Trojan_Win32_Lazy_NO_MTB{
	meta:
		description = "Trojan:Win32/Lazy.NO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {59 3b d8 72 ea f6 14 3e 57 46 e8 ?? ?? 00 00 59 3b f0 72 cb 5b 8b c7 5f 5e c9 c3 55 } //2
		$a_81_1 = {57 69 6e 64 6f 77 73 44 65 66 65 6e 64 65 72 } //1 WindowsDefender
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}