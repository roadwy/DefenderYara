
rule Trojan_Win32_Neoreblamy_NFS_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 c0 40 89 45 c0 83 7d c0 01 7d 10 8b 45 c0 } //1
		$a_03_1 = {6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 6a 04 59 6b c9 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}