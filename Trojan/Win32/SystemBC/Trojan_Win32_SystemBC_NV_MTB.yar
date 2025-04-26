
rule Trojan_Win32_SystemBC_NV_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.NV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 8a 3a f7 ff 8b 55 cc 03 55 ac 81 ea 67 2b 00 00 03 55 e8 2b d0 8b 45 d8 31 10 6a 00 e8 6d 3a f7 ff ba 04 00 00 00 2b d0 01 55 e8 6a 00 e8 5c 3a f7 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}