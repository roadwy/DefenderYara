
rule Trojan_Win64_ClipBanker_RE_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 4d 70 56 65 55 4d 6f 62 5a 6e 6f 41 4b 52 44 51 76 52 4b 37 57 6f 56 38 6b 50 53 46 43 45 51 6a 6b } //1 3MpVeUMobZnoAKRDQvRK7WoV8kPSFCEQjk
		$a_01_1 = {62 63 31 71 6e 36 34 76 78 77 33 6d 38 67 65 39 39 32 6a 70 66 6b 6c 76 76 34 65 32 6a 71 37 6b 33 34 7a 77 39 72 39 6e 6c 64 } //1 bc1qn64vxw3m8ge992jpfklvv4e2jq7k34zw9r9nld
		$a_01_2 = {4c 4e 6f 66 66 65 75 59 58 5a 44 57 75 71 35 6f 4c 51 6a 75 67 73 75 62 69 46 44 35 37 48 41 56 4d 5a } //1 LNoffeuYXZDWuq5oLQjugsubiFD57HAVMZ
		$a_01_3 = {42 69 74 63 6f 69 6e 43 6c 69 70 62 6f 61 72 64 4d 61 6c 77 61 72 65 2d 31 2d 6d 61 73 74 65 72 5c 62 74 63 63 6c 69 70 62 6f 61 72 64 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 61 76 65 72 79 2e 70 64 62 } //1 BitcoinClipboardMalware-1-master\btcclipboard\x64\Release\avery.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}