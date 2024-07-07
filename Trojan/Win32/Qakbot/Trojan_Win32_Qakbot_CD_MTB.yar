
rule Trojan_Win32_Qakbot_CD_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {4c 3f 30 3f 24 61 6c 6c 6f 63 61 74 6f 72 40 56 50 61 74 68 41 72 63 41 72 67 73 40 4d 61 67 69 63 6b 40 40 40 73 74 64 40 40 51 41 45 40 58 5a } //1 L?0?$allocator@VPathArcArgs@Magick@@@std@@QAE@XZ
		$a_01_1 = {4c 3f 30 42 6c 6f 62 40 4d 61 67 69 63 6b 40 40 51 41 45 40 58 5a } //1 L?0Blob@Magick@@QAE@XZ
		$a_01_2 = {4c 3f 30 43 6f 6c 6f 72 40 4d 61 67 69 63 6b 40 40 51 41 45 40 47 47 47 47 40 5a } //1 L?0Color@Magick@@QAE@GGGG@Z
		$a_01_3 = {4c 3f 30 43 6f 6c 6f 72 40 4d 61 67 69 63 6b 40 40 51 41 45 40 50 42 44 40 5a } //1 L?0Color@Magick@@QAE@PBD@Z
		$a_01_4 = {4c 3f 30 43 6f 6f 72 64 69 6e 61 74 65 40 4d 61 67 69 63 6b 40 40 51 41 45 40 4e 4e 40 5a } //1 L?0Coordinate@Magick@@QAE@NN@Z
		$a_01_5 = {4c 3f 30 44 72 61 77 61 62 6c 65 42 65 7a 69 65 72 40 4d 61 67 69 63 6b 40 40 51 41 45 40 41 42 56 30 31 40 40 5a } //1 L?0DrawableBezier@Magick@@QAE@ABV01@@Z
		$a_01_6 = {4c 3f 30 44 72 61 77 61 62 6c 65 46 69 6c 6c 52 75 6c 65 40 4d 61 67 69 63 6b 40 40 51 41 45 40 57 34 46 69 6c 6c 52 75 6c 65 40 4d 61 67 69 63 6b 43 6f 72 65 40 40 40 5a } //1 L?0DrawableFillRule@Magick@@QAE@W4FillRule@MagickCore@@@Z
		$a_01_7 = {4c 3f 30 44 72 61 77 61 62 6c 65 53 74 72 6f 6b 65 41 6e 74 69 61 6c 69 61 73 40 4d 61 67 69 63 6b 40 40 51 41 45 40 5f 4e 40 5a } //1 L?0DrawableStrokeAntialias@Magick@@QAE@_N@Z
		$a_01_8 = {4c 73 74 72 6f 6b 65 4d 69 74 65 72 4c 69 6d 69 74 40 49 6d 61 67 65 40 4d 61 67 69 63 6b 40 40 51 41 45 58 49 40 5a } //1 LstrokeMiterLimit@Image@Magick@@QAEXI@Z
		$a_01_9 = {4c 73 77 69 72 6c 40 49 6d 61 67 65 40 4d 61 67 69 63 6b 40 40 51 41 45 58 4e 40 5a } //1 Lswirl@Image@Magick@@QAEXN@Z
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}