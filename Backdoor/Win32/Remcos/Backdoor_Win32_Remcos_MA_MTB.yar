
rule Backdoor_Win32_Remcos_MA_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {e0 00 02 03 0b 01 03 00 00 ea 09 00 00 3e 01 00 00 00 00 00 f0 e3 05 00 00 10 00 00 00 30 1b 00 00 00 40 00 00 10 } //02 00 
		$a_01_1 = {4d 61 63 68 69 6e 65 01 07 4d 61 70 4b 65 79 73 01 07 4e 61 6d 65 6c 65 6e 01 07 4e 65 77 50 72 6f 63 01 07 4f 62 6a 4e 61 6d 65 01 07 50 6b 67 50 61 74 68 01 07 50 6f 69 6e 74 65 72 01 07 50 72 6f } //02 00  慍档湩ť䴇灡敋獹܁慎敭敬Ů万睥牐捯܁扏乪浡ť倇杫慐桴܁潐湩整Ų倇潲
		$a_01_2 = {3a 2f 55 73 65 72 73 2f 41 64 6d 69 6e 2f 41 70 70 44 61 74 61 2f 52 6f 61 6d 69 6e 67 2f 69 6e 73 74 61 6c 6c 65 72 2f 69 6e 73 74 61 6c 6c 65 72 2f 6d 61 69 6e 2e 67 6f } //00 00  :/Users/Admin/AppData/Roaming/installer/installer/main.go
	condition:
		any of ($a_*)
 
}