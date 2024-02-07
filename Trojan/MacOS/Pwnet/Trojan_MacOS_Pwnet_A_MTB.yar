
rule Trojan_MacOS_Pwnet_A_MTB{
	meta:
		description = "Trojan:MacOS/Pwnet.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {76 6c 6f 6e 65 2e 63 63 } //01 00  vlone.cc
		$a_00_1 = {2f 70 72 69 76 61 74 65 2f 2e 64 69 73 63 6f 72 64 2f 78 6d 72 2e 7a 69 70 } //01 00  /private/.discord/xmr.zip
		$a_01_2 = {69 6e 73 74 61 6c 6c 4d 69 6e 65 72 45 76 } //01 00  installMinerEv
		$a_00_3 = {70 77 6e 65 64 6e 65 74 2f 70 77 6e 65 64 6e 65 74 2f } //01 00  pwnednet/pwnednet/
		$a_01_4 = {4c 6f 61 64 4d 69 6e 65 72 45 76 } //00 00  LoadMinerEv
		$a_00_5 = {5d 04 00 } //00 f5 
	condition:
		any of ($a_*)
 
}