
rule Trojan_Win64_Tedy_GPJ_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_80_0 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 31 32 32 33 31 33 33 34 39 38 35 35 30 39 31 31 30 36 37 2f 31 32 33 31 33 35 38 36 37 36 32 32 35 33 35 39 39 33 32 2f 73 76 68 6f 73 74 2e 65 78 65 } //cdn.discordapp.com/attachments/1223133498550911067/1231358676225359932/svhost.exe  5
		$a_80_1 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 } //cdn.discordapp.com/attachments  1
		$a_80_2 = {63 65 73 2e 65 78 65 } //ces.exe  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=7
 
}