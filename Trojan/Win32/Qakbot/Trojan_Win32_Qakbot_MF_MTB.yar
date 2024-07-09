
rule Trojan_Win32_Qakbot_MF_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 0f 82 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_MF_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 50 0c 8b 48 70 8b ?? 94 00 00 00 88 1c 0a ff 40 70 8b 50 70 8b 88 94 00 00 00 8b 5c 24 28 88 1c 0a ff 40 70 8b 48 68 81 f1 ?? ?? ?? ?? 29 48 48 8b 88 80 00 00 00 09 88 c4 00 00 00 8b 88 a0 00 00 00 01 88 88 00 00 00 81 ff ?? ?? ?? ?? 0f 8c } //10
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //2 DllRegisterServer
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}
rule Trojan_Win32_Qakbot_MF_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {00 6d 76 5f 61 64 64 5f 69 00 } //1 洀彶摡彤i
		$a_01_1 = {6d 76 5f 61 64 6c 65 72 33 32 5f 75 70 64 61 74 65 } //1 mv_adler32_update
		$a_01_2 = {6d 76 5f 61 65 73 5f 61 6c 6c 6f 63 } //1 mv_aes_alloc
		$a_01_3 = {6d 76 5f 61 65 73 5f 63 74 72 5f 69 6e 63 72 65 6d 65 6e 74 5f 69 76 } //1 mv_aes_ctr_increment_iv
		$a_01_4 = {6d 76 5f 61 73 73 65 72 74 30 5f 66 70 75 } //1 mv_assert0_fpu
		$a_01_5 = {6d 76 5f 62 6c 6f 77 66 69 73 68 5f 63 72 79 70 74 } //1 mv_blowfish_crypt
		$a_01_6 = {6d 76 5f 61 75 64 69 6f 5f 66 69 66 6f 5f 64 72 61 69 6e } //1 mv_audio_fifo_drain
		$a_01_7 = {6d 76 5f 61 75 64 69 6f 5f 66 69 66 6f 5f 70 65 65 6b 5f 61 74 } //1 mv_audio_fifo_peek_at
		$a_01_8 = {6d 76 5f 63 61 6d 65 6c 6c 69 61 5f 63 72 79 70 74 } //1 mv_camellia_crypt
		$a_01_9 = {6e 65 78 74 } //1 next
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}