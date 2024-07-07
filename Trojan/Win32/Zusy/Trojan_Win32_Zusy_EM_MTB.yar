
rule Trojan_Win32_Zusy_EM_MTB{
	meta:
		description = "Trojan:Win32/Zusy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 02 4b 81 c2 04 00 00 00 bb 90 ae f3 c2 21 d9 39 fa 75 e7 21 f3 c3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Zusy_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {45 78 6f 64 75 73 5c 65 78 6f 64 75 73 2e 77 61 6c 6c 65 74 } //1 Exodus\exodus.wallet
		$a_01_1 = {45 74 68 65 72 65 75 6d 5c 6b 65 79 73 74 6f 72 65 } //1 Ethereum\keystore
		$a_01_2 = {4d 6f 6f 6e 63 68 69 6c 64 20 50 72 6f 64 75 63 74 69 6f 6e 73 5c 50 61 6c 65 20 4d 6f 6f 6e } //1 Moonchild Productions\Pale Moon
		$a_01_3 = {4f 75 74 6c 6f 6f 6b 5c 39 33 37 35 43 46 46 30 34 31 33 31 31 31 64 33 42 38 38 41 30 30 31 30 34 42 32 41 36 36 37 36 } //1 Outlook\9375CFF0413111d3B88A00104B2A6676
		$a_01_4 = {4e 4e 54 50 20 45 6d 61 69 6c 20 41 64 64 72 65 73 73 } //1 NNTP Email Address
		$a_01_5 = {63 66 62 70 69 65 6d 6e 6b 64 70 6f 6d } //1 cfbpiemnkdpom
		$a_01_6 = {53 4d 54 50 20 55 73 65 72 20 4e 61 6d 65 } //1 SMTP User Name
		$a_01_7 = {47 72 61 62 62 65 72 } //1 Grabber
		$a_01_8 = {67 65 63 6b 6f 5f 62 72 6f 77 73 65 72 73 } //1 gecko_browsers
		$a_01_9 = {57 61 6c 6c 65 74 73 } //1 Wallets
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}
rule Trojan_Win32_Zusy_EM_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {53 69 6d 70 6c 65 50 72 6f 67 72 61 6d 44 65 62 75 67 67 65 72 } //1 SimpleProgramDebugger
		$a_81_1 = {48 65 61 70 4d 65 6d 56 69 65 77 } //1 HeapMemView
		$a_81_2 = {44 4c 4c 45 78 70 6f 72 74 56 69 65 77 65 72 } //1 DLLExportViewer
		$a_81_3 = {59 6f 75 20 61 72 65 20 62 61 6e 6e 65 64 2c 20 63 6f 6e 74 61 63 74 20 61 6e 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 21 } //1 You are banned, contact an administrator!
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 73 5c 75 68 6c 6f 61 64 65 72 5f 5b 75 6e 6b 6e 6f 77 6e 63 68 65 61 74 73 2e 6d 65 5d 5f 2e 64 6c 6c } //1 Downloads\uhloader_[unknowncheats.me]_.dll
		$a_81_5 = {55 6e 77 61 6e 74 65 64 20 70 72 6f 67 72 61 6d 73 20 64 65 74 65 63 74 65 64 } //1 Unwanted programs detected
		$a_81_6 = {53 75 73 70 65 6e 64 65 64 20 74 68 65 20 70 72 6f 63 65 73 73 20 66 6f 72 20 62 79 70 61 73 73 } //1 Suspended the process for bypass
		$a_81_7 = {74 68 72 65 61 64 20 6d 61 6e 69 70 75 6c 61 74 69 6f 6e 20 61 74 74 65 6d 70 74 20 5b 49 6e 6a 65 63 74 5d 20 76 32 } //1 thread manipulation attempt [Inject] v2
		$a_81_8 = {5c 58 6f 72 5f 50 6c 75 73 5c 53 70 6c 61 73 68 5c 58 6f 72 2d 68 61 63 6b 2e 62 6d 70 } //1 \Xor_Plus\Splash\Xor-hack.bmp
		$a_81_9 = {44 61 74 61 2f 4c 6f 63 61 6c 2f 7a 2e 6a 70 65 67 } //1 Data/Local/z.jpeg
		$a_81_10 = {2f 42 61 6e 48 77 49 44 2f 42 61 6e 48 77 49 44 2e 74 78 74 } //1 /BanHwID/BanHwID.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}