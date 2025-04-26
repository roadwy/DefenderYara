
rule Trojan_Win32_Fersip_A{
	meta:
		description = "Trojan:Win32/Fersip.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 69 6e 65 72 73 6f 75 72 63 65 5c 52 65 6c 65 61 73 65 5c 62 69 74 63 6f 69 6e 2d 6d 69 6e 65 72 2e 70 64 62 } //1 minersource\Release\bitcoin-miner.pdb
		$a_01_1 = {53 00 33 00 66 00 6d 00 77 00 66 00 67 00 64 00 66 00 77 00 61 00 64 00 61 00 77 00 33 00 33 00 64 00 44 00 64 00 } //1 S3fmwfgdfwadaw33dDd
		$a_01_2 = {6d 00 73 00 76 00 63 00 73 00 69 00 70 00 34 00 2e 00 65 00 78 00 65 00 } //1 msvcsip4.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}