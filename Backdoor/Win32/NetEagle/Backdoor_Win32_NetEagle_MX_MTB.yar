
rule Backdoor_Win32_NetEagle_MX_MTB{
	meta:
		description = "Backdoor:Win32/NetEagle.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 0c 02 8a 04 02 2a c2 34 ef 8a d8 c0 eb 06 c0 e0 02 0a d8 42 3b 54 24 ?? 88 19 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}