
rule TrojanDownloader_Win32_Loan_BG_MTB{
	meta:
		description = "TrojanDownloader:Win32/Loan.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 4c 24 14 8b c1 33 c9 85 c0 76 0d 80 b4 0c 30 02 00 00 99 41 3b c8 72 f3 ff 74 24 10 50 8d 84 24 [0-04] 6a 01 50 ff 15 [0-04] 01 44 24 24 56 55 8d 84 24 [0-04] 6a 01 50 ff d3 83 c4 20 eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}