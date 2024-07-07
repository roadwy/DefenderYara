
rule Trojan_Win32_Rugmi_RH_MTB{
	meta:
		description = "Trojan:Win32/Rugmi.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 3a 5c 66 69 5c 47 50 55 5c 53 53 44 5c 34 6f 5c 73 77 69 74 63 68 5c 53 79 6e 63 68 72 6f 6e 69 7a 61 74 69 6f 6e 5c 42 75 66 66 65 72 5c 6f 65 5c 78 38 36 5c 64 65 62 75 67 5c 73 65 72 76 65 72 5c 66 69 72 6d 2e 70 64 62 } //5 P:\fi\GPU\SSD\4o\switch\Synchronization\Buffer\oe\x86\debug\server\firm.pdb
		$a_01_1 = {56 75 31 8b 35 70 90 46 00 8b ce ff 75 08 33 35 dc b5 46 00 83 e1 1f d3 ce } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}