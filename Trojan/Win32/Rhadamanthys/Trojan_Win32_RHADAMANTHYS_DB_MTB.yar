
rule Trojan_Win32_RHADAMANTHYS_DB_MTB{
	meta:
		description = "Trojan:Win32/RHADAMANTHYS.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,47 00 47 00 0b 00 00 "
		
	strings :
		$a_81_0 = {53 44 4c 5f 41 74 6f 6d 69 63 47 65 74 50 74 72 } //10 SDL_AtomicGetPtr
		$a_81_1 = {53 44 4c 5f 41 74 6f 6d 69 63 53 65 74 50 74 72 } //10 SDL_AtomicSetPtr
		$a_81_2 = {53 44 4c 5f 42 75 69 6c 64 41 75 64 69 6f 43 56 54 } //10 SDL_BuildAudioCVT
		$a_81_3 = {53 44 4c 5f 41 75 64 69 6f 53 74 72 65 61 6d 47 65 74 } //10 SDL_AudioStreamGet
		$a_81_4 = {53 44 4c 5f 41 75 64 69 6f 53 74 72 65 61 6d 50 75 74 } //10 SDL_AudioStreamPut
		$a_81_5 = {53 44 4c 5f 41 75 64 69 6f 53 74 72 65 61 6d 46 6c 75 73 68 } //10 SDL_AudioStreamFlush
		$a_81_6 = {53 44 4c 32 2e 64 6c 6c } //10 SDL2.dll
		$a_81_7 = {41 6c 70 68 61 42 6c 65 6e 64 } //1 AlphaBlend
		$a_81_8 = {54 72 61 6e 73 70 61 72 65 6e 74 42 } //1 TransparentB
		$a_81_9 = {43 72 65 61 74 65 46 6f 6e 74 50 61 63 6b 61 } //1 CreateFontPacka
		$a_81_10 = {47 72 61 64 69 65 6e 74 46 69 6c 6c } //1 GradientFill
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10+(#a_81_5  & 1)*10+(#a_81_6  & 1)*10+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=71
 
}