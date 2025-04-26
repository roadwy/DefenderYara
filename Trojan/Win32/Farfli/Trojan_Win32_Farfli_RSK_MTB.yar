
rule Trojan_Win32_Farfli_RSK_MTB{
	meta:
		description = "Trojan:Win32/Farfli.RSK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 30 8b 55 10 30 1c 32 8a 14 32 30 14 30 8a 14 30 8b 5d 10 30 14 33 48 ff 45 10 8b d0 2b 55 10 83 fa 01 7d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}