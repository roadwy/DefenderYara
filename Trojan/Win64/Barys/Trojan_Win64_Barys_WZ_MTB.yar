
rule Trojan_Win64_Barys_WZ_MTB{
	meta:
		description = "Trojan:Win64/Barys.WZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {64 69 73 63 6f 72 64 2e 63 6f 6d 2f 61 70 69 2f 77 65 62 68 6f 6f 6b 73 2f } //1 discord.com/api/webhooks/
		$a_81_1 = {63 75 72 6c 20 2d 69 20 2d 48 20 22 41 63 63 65 70 74 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6a 73 6f 6e 22 20 2d 48 20 22 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6a 73 6f 6e 22 20 2d 58 20 50 4f 53 54 20 2d 2d 64 61 74 61 } //1 curl -i -H "Accept: application/json" -H "Content-Type:application/json" -X POST --data
		$a_81_2 = {26 26 20 74 69 6d 65 6f 75 74 20 2f 74 20 35 20 3e 6e 75 6c 20 32 3e 26 31 } //1 && timeout /t 5 >nul 2>&1
		$a_81_3 = {73 74 61 72 74 20 63 6d 64 20 2f 43 20 22 63 6f 6c 6f 72 20 62 20 26 26 20 74 69 74 6c 65 20 45 72 72 6f 72 20 26 26 20 65 63 68 6f } //1 start cmd /C "color b && title Error && echo
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}