
rule Trojan_Win32_Luder_C{
	meta:
		description = "Trojan:Win32/Luder.C,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0d 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {36 33 32 74 72 36 37 32 33 38 72 32 67 66 36 32 33 67 66 79 32 75 69 67 66 79 75 66 69 67 79 65 77 67 66 65 79 66 } //03 00  632tr67238r2gf623gfy2uigfyufigyewgfeyf
		$a_01_1 = {33 69 32 37 66 67 69 32 39 38 66 37 67 66 69 75 65 77 67 66 75 67 65 66 75 79 67 69 78 6e 79 67 69 66 79 78 75 67 69 66 78 79 34 33 67 78 34 33 66 } //03 00  3i27fgi298f7gfiuewgfugefuygixnygifyxugifxy43gx43f
		$a_01_2 = {6d 75 63 6f 31 } //01 00  muco1
		$a_01_3 = {52 69 6f 20 47 72 61 6e 64 65 } //02 00  Rio Grande
		$a_01_4 = {41 6c 6f 6e 7a 6f } //0a 00  Alonzo
		$a_02_5 = {55 8b ec 81 c4 fc fe ff ff 8d 05 90 01 03 00 e8 90 01 03 00 50 8d 85 fc fe ff ff 50 68 04 01 00 00 e8 90 01 03 00 90 90 e8 90 01 03 00 59 33 c1 60 eb 0b 33 c0 21 36 21 16 2c 58 2c 21 16 8b cb c1 e8 02 f7 db 61 8b d0 ff 75 08 52 8d 15 14 11 40 00 52 87 d2 8d 95 fc fe ff ff 52 8d 15 90 01 03 00 c1 c0 0c ff d2 c9 c2 04 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}