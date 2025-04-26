
rule Trojan_Win32_Fauppod_IP_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.IP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 8b 72 30 8b 76 0c 8b 76 0c ad 8b 30 8b 7e 18 8b 5f 3c 8b 5c 1f 78 8b 74 1f 20 01 fe } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}