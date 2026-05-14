
rule Trojan_Win32_Farfli_LMD_MTB{
	meta:
		description = "Trojan:Win32/Farfli.LMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 06 00 00 "
		
	strings :
		$a_01_0 = {0f bf 44 24 04 d1 c2 c1 f8 3e 42 89 04 04 66 c1 e0 0e 58 } //10
		$a_81_1 = {6d 75 73 69 63 2e 74 71 2e 6a 69 6e 63 68 61 6e 67 68 72 2e 76 69 70 2e 69 6f 73 } //2 music.tq.jinchanghr.vip.ios
		$a_81_2 = {75 70 6c 6f 61 64 2f 74 5f 73 6f 75 6e 64 5f 72 65 63 6f 6d 6d 65 6e 64 45 66 66 65 63 74 42 61 73 65 2f 33 34 36 31 34 30 37 2e 70 6e 67 } //3 upload/t_sound_recommendEffectBase/3461407.png
		$a_81_3 = {73 73 32 2f 61 75 64 69 6f 65 66 66 65 63 74 49 63 6f 2f 6c 69 73 74 49 63 6f 6e 2f 52 65 63 6f 6d 6d 65 6e 64 49 63 6f 6e 31 33 2e 70 6e 67 } //5 ss2/audioeffectIco/listIcon/RecommendIcon13.png
		$a_81_4 = {69 72 73 5c 33 36 61 66 33 30 66 39 32 30 66 30 65 33 66 30 30 32 33 32 66 66 32 34 62 31 62 37 38 34 37 62 32 63 30 30 36 31 39 38 2e 65 6e 63 } //6 irs\36af30f920f0e3f00232ff24b1b7847b2c006198.enc
		$a_81_5 = {63 6c 6e 74 75 70 61 74 65 2f 73 73 32 2f 61 75 64 69 6f 65 66 66 65 63 74 49 63 6f 2f 6c 69 73 74 49 63 6f 6e } //7 clntupate/ss2/audioeffectIco/listIcon
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*5+(#a_81_4  & 1)*6+(#a_81_5  & 1)*7) >=33
 
}