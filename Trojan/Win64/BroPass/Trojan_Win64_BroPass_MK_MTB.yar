
rule Trojan_Win64_BroPass_MK_MTB{
	meta:
		description = "Trojan:Win64/BroPass.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 05 00 00 "
		
	strings :
		$a_03_0 = {33 db 4c 8b c8 48 89 5c 24 30 45 33 c0 89 5c 24 28 33 d2 49 8b ce 4c 89 7c 24 20 ?? ?? ?? ?? ?? ?? 48 83 ?? ?? 48 8b f0 48 0f 44 f3 48 85 f6 } //20
		$a_81_1 = {54 45 4c 45 47 52 41 4d 5f 54 4f 4b 45 4e } //5 TELEGRAM_TOKEN
		$a_81_2 = {44 49 53 43 4f 52 44 5f 57 45 42 48 4f 4f 4b } //5 DISCORD_WEBHOOK
		$a_81_3 = {2d 2d 68 65 61 64 6c 65 73 73 3d 6e 65 77 } //3 --headless=new
		$a_81_4 = {2d 2d 6e 6f 2d 73 61 6e 64 62 6f 78 20 2d 2d 64 69 73 61 62 6c 65 2d 67 70 75 } //2 --no-sandbox --disable-gpu
	condition:
		((#a_03_0  & 1)*20+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*3+(#a_81_4  & 1)*2) >=35
 
}