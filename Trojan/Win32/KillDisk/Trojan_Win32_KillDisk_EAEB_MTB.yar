
rule Trojan_Win32_KillDisk_EAEB_MTB{
	meta:
		description = "Trojan:Win32/KillDisk.EAEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ca c1 e9 10 d3 ea 8b 8d dc ac f8 ff 8b c1 c1 e8 06 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}