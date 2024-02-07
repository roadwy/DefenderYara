
rule Trojan_Win64_T1098_AccountManipulation_A{
	meta:
		description = "Trojan:Win64/T1098_AccountManipulation.A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 3a 00 3a 00 64 00 63 00 73 00 68 00 61 00 64 00 6f 00 77 00 } //0a 00  lsadump::dcshadow
		$a_01_1 = {6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 3a 00 3a 00 64 00 63 00 73 00 79 00 6e 00 63 00 } //0a 00  lsadump::dcsync
		$a_01_2 = {6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 3a 00 3a 00 70 00 6f 00 73 00 74 00 7a 00 65 00 72 00 6f 00 6c 00 6f 00 67 00 6f 00 6e 00 } //0a 00  lsadump::postzerologon
		$a_01_3 = {6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 3a 00 3a 00 73 00 65 00 74 00 6e 00 74 00 6c 00 6d 00 } //0a 00  lsadump::setntlm
		$a_01_4 = {6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 3a 00 3a 00 63 00 68 00 61 00 6e 00 67 00 65 00 6e 00 74 00 6c 00 6d 00 } //0a 00  lsadump::changentlm
		$a_01_5 = {6d 00 69 00 73 00 63 00 3a 00 3a 00 73 00 6b 00 65 00 6c 00 65 00 74 00 6f 00 6e 00 } //0a 00  misc::skeleton
		$a_01_6 = {73 00 69 00 64 00 3a 00 3a 00 6d 00 6f 00 64 00 69 00 66 00 79 00 } //0a 00  sid::modify
		$a_01_7 = {73 00 69 00 64 00 3a 00 3a 00 70 00 61 00 74 00 63 00 68 00 } //0a 00  sid::patch
		$a_01_8 = {6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 3a 00 3a 00 7a 00 65 00 72 00 6f 00 6c 00 6f 00 67 00 6f 00 6e 00 } //00 00  lsadump::zerologon
	condition:
		any of ($a_*)
 
}