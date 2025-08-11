
rule Trojan_Win64_DeedRAT_GALA_MTB{
	meta:
		description = "Trojan:Win64/DeedRAT.GALA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //8 vssadmin delete shadows /all /quiet
		$a_81_1 = {77 65 62 68 6f 6f 6b 73 2f 59 4f 55 52 5f 57 45 42 48 4f 4f 4b 5f 48 45 52 45 } //1 webhooks/YOUR_WEBHOOK_HERE
		$a_81_2 = {64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 } //1 decrypt your files
	condition:
		((#a_81_0  & 1)*8+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=10
 
}