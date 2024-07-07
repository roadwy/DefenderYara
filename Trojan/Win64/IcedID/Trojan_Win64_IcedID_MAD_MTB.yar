
rule Trojan_Win64_IcedID_MAD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6f 76 77 35 51 2e 64 6c 6c } //1 ovw5Q.dll
		$a_01_1 = {4a 68 73 61 64 6a 71 6b } //1 Jhsadjqk
		$a_01_2 = {48 69 65 38 38 71 33 57 76 } //1 Hie88q3Wv
		$a_01_3 = {6d 4a 67 38 52 63 4c 31 } //1 mJg8RcL1
		$a_01_4 = {75 38 37 77 64 50 75 46 57 63 } //1 u87wdPuFWc
		$a_01_5 = {78 6c 78 43 59 44 65 75 74 35 75 } //1 xlxCYDeut5u
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}