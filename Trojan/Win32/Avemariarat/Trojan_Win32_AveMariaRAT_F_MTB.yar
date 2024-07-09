
rule Trojan_Win32_AveMariaRAT_F_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRAT.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0b c0 c8 ?? 32 87 ?? ?? ?? ?? 41 88 44 ?? ff 8d 47 ?? 99 bf ?? ?? ?? ?? f7 ff 8b fa 3b ce 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}