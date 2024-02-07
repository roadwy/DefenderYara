
rule Trojan_Win32_Gozi_HQ_MTB{
	meta:
		description = "Trojan:Win32/Gozi.HQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 6c 5c 76 6f 69 79 5c 54 79 72 61 63 6c 2e 70 64 62 } //01 00  Intel\voiy\Tyracl.pdb
		$a_01_1 = {7a 37 5a 44 74 68 61 74 68 6e 73 68 61 6c 6c 6d 61 6e 2e 64 72 79 } //01 00  z7ZDthathnshallman.dry
		$a_01_2 = {62 65 61 73 74 51 4c 5a 64 53 72 } //01 00  beastQLZdSr
		$a_01_3 = {57 68 61 6c 65 73 76 63 72 65 61 74 65 64 74 68 61 74 2e 44 69 76 69 64 65 64 74 68 65 72 65 50 75 70 6f 6e 61 6f 75 72 } //00 00  Whalesvcreatedthat.DividedtherePuponaour
	condition:
		any of ($a_*)
 
}