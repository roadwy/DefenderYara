
rule Ransom_Linux_DesktopWallpaperChange_A{
	meta:
		description = "Ransom:Linux/DesktopWallpaperChange.A,SIGNATURE_TYPE_CMDHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_00_0 = {67 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 20 00 73 00 65 00 74 00 20 00 } //10 gsettings set 
		$a_00_1 = {6f 00 72 00 67 00 2e 00 67 00 6e 00 6f 00 6d 00 65 00 2e 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 62 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 20 00 } //10 org.gnome.desktop.background 
		$a_00_2 = {6f 00 72 00 67 00 2e 00 63 00 69 00 6e 00 6e 00 61 00 6d 00 6f 00 6e 00 2e 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 62 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 20 00 } //10 org.cinnamon.desktop.background 
		$a_00_3 = {70 00 69 00 63 00 74 00 75 00 72 00 65 00 2d 00 75 00 72 00 69 00 } //10 picture-uri
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=30
 
}