
rule Backdoor_Linux_Fysbis_A_dha{
	meta:
		description = "Backdoor:Linux/Fysbis.A!dha,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 0a 00 00 02 00 "
		
	strings :
		$a_00_0 = {6c 73 20 2f 65 74 63 20 7c 20 65 67 72 65 70 20 2d 65 22 66 65 64 6f 72 61 2a 7c 64 65 62 69 61 6e 2a 7c 67 65 6e 74 6f 6f 2a 7c 6d 61 6e 64 72 69 76 61 2a 7c 6d 61 6e 64 72 61 6b 65 2a 7c 6d 65 65 67 6f 2a 7c 72 65 64 68 61 74 2a 7c 6c 73 62 2d 2a 7c 73 75 6e 2d 2a 7c 53 55 53 45 2a 7c 72 65 6c 65 61 73 65 22 } //02 00  ls /etc | egrep -e"fedora*|debian*|gentoo*|mandriva*|mandrake*|meego*|redhat*|lsb-*|sun-*|SUSE*|release"
		$a_00_1 = {70 67 72 65 70 20 2d 6c 20 22 67 6e 6f 6d 65 7c 6b 64 65 7c 6d 61 74 65 7c 63 69 6e 6e 61 6d 6f 6e 7c 6c 78 64 65 7c 78 66 63 65 7c 6a 77 6d 22 } //01 00  pgrep -l "gnome|kde|mate|cinnamon|lxde|xfce|jwm"
		$a_00_2 = {00 31 31 52 65 6d 6f 74 65 53 68 65 6c 6c 00 } //01 00 
		$a_00_3 = {59 6f 75 72 20 63 6f 6d 6d 61 6e 64 20 6e 6f 74 20 77 72 69 74 65 64 20 74 6f 20 70 69 70 65 } //01 00  Your command not writed to pipe
		$a_00_4 = {54 65 72 6d 69 6e 61 6c 20 64 6f 6e 60 74 20 73 74 61 72 74 65 64 } //01 00  Terminal don`t started
		$a_00_5 = {54 65 72 6d 69 6e 61 6c 20 64 6f 6e 60 74 20 73 74 6f 70 70 65 64 } //01 00  Terminal don`t stopped
		$a_00_6 = {54 65 72 6d 69 6e 61 6c 20 79 65 74 20 73 74 61 72 74 65 64 } //01 00  Terminal yet started
		$a_00_7 = {54 65 72 6d 69 6e 61 6c 20 79 65 74 20 73 74 6f 70 70 65 64 } //01 00  Terminal yet stopped
		$a_00_8 = {54 65 72 6d 69 6e 61 6c 20 64 6f 6e 60 74 20 73 74 61 72 74 65 64 20 66 6f 72 20 65 78 65 63 75 74 69 6e 67 20 63 6f 6d 6d 61 6e 64 } //01 00  Terminal don`t started for executing command
		$a_00_9 = {3c 63 61 70 74 69 6f 6e 3e 3c 66 6f 6e 74 20 73 69 7a 65 3d 34 20 63 6f 6c 6f 72 3d 72 65 64 3e 54 41 42 4c 45 20 45 58 45 43 55 54 45 20 46 49 4c 45 53 3c 2f 66 6f 6e 74 3e 3c 2f 63 61 70 74 69 6f 6e 3e } //00 00  <caption><font size=4 color=red>TABLE EXECUTE FILES</font></caption>
	condition:
		any of ($a_*)
 
}