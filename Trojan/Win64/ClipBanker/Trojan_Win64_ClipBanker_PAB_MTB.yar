
rule Trojan_Win64_ClipBanker_PAB_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_81_0 = {42 75 69 6c 64 20 43 6c 69 70 70 65 72 } //1 Build Clipper
		$a_81_1 = {43 6f 6e 66 69 67 20 63 6f 70 69 65 64 20 74 6f 20 63 6c 69 70 62 6f 61 72 64 21 } //1 Config copied to clipboard!
		$a_81_2 = {68 74 74 70 73 3a 2f 2f 74 2e 6d 65 2f 61 72 63 65 6e 75 73 63 6c 69 70 70 65 72 } //2 https://t.me/arcenusclipper
		$a_81_3 = {50 61 73 74 65 62 69 6e 20 52 61 77 20 55 52 4c 3a } //2 Pastebin Raw URL:
		$a_81_4 = {2f 73 65 6e 64 4d 65 73 73 61 67 65 3f 63 68 61 74 5f 69 64 3d } //1 /sendMessage?chat_id=
		$a_81_5 = {2f 43 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 33 20 3e 20 6e 75 6c 20 26 20 64 65 6c } //2 /C ping 127.0.0.1 -n 3 > nul & del
		$a_81_6 = {77 61 6c 6c 63 6f 6d 2e 74 78 74 } //1 wallcom.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1+(#a_81_5  & 1)*2+(#a_81_6  & 1)*1) >=10
 
}