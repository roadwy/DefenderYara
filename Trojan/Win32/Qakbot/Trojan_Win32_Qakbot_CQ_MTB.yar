
rule Trojan_Win32_Qakbot_CQ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 3f 30 3f 24 42 61 73 65 48 61 73 68 40 56 4f 55 53 74 72 69 6e 67 40 72 74 6c 40 40 40 66 72 61 6d 65 77 6f 72 6b 40 40 51 41 45 40 58 5a } //1 P?0?$BaseHash@VOUString@rtl@@@framework@@QAE@XZ
		$a_01_1 = {50 3f 30 43 6f 6e 73 74 49 74 65 6d 43 6f 6e 74 61 69 6e 65 72 40 66 72 61 6d 65 77 6f 72 6b 40 40 51 41 45 40 41 42 56 30 31 40 40 5a } //1 P?0ConstItemContainer@framework@@QAE@ABV01@@Z
		$a_01_2 = {50 3f 30 48 61 6e 64 6c 65 72 43 46 47 41 63 63 65 73 73 40 66 72 61 6d 65 77 6f 72 6b 40 40 51 41 45 40 41 42 56 30 31 40 40 5a } //1 P?0HandlerCFGAccess@framework@@QAE@ABV01@@Z
		$a_01_3 = {50 3f 30 49 74 65 6d 43 6f 6e 74 61 69 6e 65 72 40 66 72 61 6d 65 77 6f 72 6b 40 40 51 41 45 40 41 42 56 53 68 61 72 65 61 62 6c 65 4d 75 74 65 78 40 31 40 40 5a } //1 P?0ItemContainer@framework@@QAE@ABVShareableMutex@1@@Z
		$a_01_4 = {50 3f 30 4c 6f 63 6b 48 65 6c 70 65 72 40 66 72 61 6d 65 77 6f 72 6b 40 40 51 41 45 40 50 41 56 49 4d 75 74 65 78 40 76 6f 73 40 40 40 5a } //1 P?0LockHelper@framework@@QAE@PAVIMutex@vos@@@Z
		$a_01_5 = {54 69 6d 65 } //10 Time
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*10) >=15
 
}