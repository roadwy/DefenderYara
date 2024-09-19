
rule Ransom_Linux_DesktpWallpaperChange_B{
	meta:
		description = "Ransom:Linux/DesktpWallpaperChange.B,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {66 00 65 00 68 00 20 00 2d 00 2d 00 62 00 67 00 2d 00 73 00 63 00 61 00 6c 00 65 00 20 00 } //10 feh --bg-scale 
	condition:
		((#a_00_0  & 1)*10) >=10
 
}