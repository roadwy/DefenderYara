
rule TrojanClicker_BAT_Small_ARAX_MTB{
	meta:
		description = "TrojanClicker:BAT/Small.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 64 65 61 64 65 79 65 32 2e 70 64 62 } //05 00  \deadeye2.pdb
		$a_00_1 = {2f 00 76 00 69 00 65 00 77 00 5f 00 76 00 69 00 64 00 65 00 6f 00 2e 00 70 00 68 00 70 00 3f 00 76 00 69 00 65 00 77 00 6b 00 65 00 79 00 3d 00 } //05 00  /view_video.php?viewkey=
		$a_00_2 = {2d 00 2d 00 6d 00 75 00 74 00 65 00 2d 00 61 00 75 00 64 00 69 00 6f 00 } //02 00  --mute-audio
		$a_00_3 = {5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 } //02 00  \Google\Chrome\User Data
		$a_00_4 = {77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 73 00 63 00 72 00 6f 00 6c 00 6c 00 42 00 79 00 28 00 30 00 2c 00 20 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 69 00 6e 00 6e 00 65 00 72 00 48 00 65 00 69 00 67 00 68 00 74 00 20 00 2a 00 20 00 32 00 29 00 } //00 00  window.scrollBy(0, window.innerHeight * 2)
	condition:
		any of ($a_*)
 
}