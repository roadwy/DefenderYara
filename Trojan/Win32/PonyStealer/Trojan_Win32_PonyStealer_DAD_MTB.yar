
rule Trojan_Win32_PonyStealer_DAD_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.DAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 45 f4 50 6a 04 8b 45 08 83 c0 38 50 8b 45 08 ff 70 34 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}