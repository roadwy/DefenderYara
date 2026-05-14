
rule Trojan_Win32_GCleaner_RAM_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.RAM!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 bc 03 55 ac 81 ea b2 84 31 00 2b d7 03 c2 50 6a 00 e8 67 ed fa ff 5a 2b d0 31 13 83 c6 04 83 c3 04 3b 75 d4 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}