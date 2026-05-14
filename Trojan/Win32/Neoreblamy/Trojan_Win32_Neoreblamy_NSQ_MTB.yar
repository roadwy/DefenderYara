
rule Trojan_Win32_Neoreblamy_NSQ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NSQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 8b 45 b0 40 89 45 b0 83 7d b0 01 7d 0d 8b 45 b0 } //1
		$a_01_1 = {eb 07 8b 45 c4 48 89 45 c4 83 7d c4 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}