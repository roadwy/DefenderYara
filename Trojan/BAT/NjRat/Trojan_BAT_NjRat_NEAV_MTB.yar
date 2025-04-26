
rule Trojan_BAT_NjRat_NEAV_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 35 64 38 31 38 35 37 31 2d 64 63 39 64 2d 34 62 31 39 2d 61 38 62 38 2d 61 33 65 64 66 35 37 64 66 31 66 36 } //10 $5d818571-dc9d-4b19-a8b8-a3edf57df1f6
		$a_01_1 = {43 4f 4e 54 45 52 20 46 49 4c 4d 2e 65 78 65 } //5 CONTER FILM.exe
		$a_01_2 = {53 79 73 74 65 6d 2e 57 69 6e 64 6f 77 73 2e 46 6f 72 6d 73 2e 44 61 74 61 56 69 73 75 61 6c 69 7a 61 74 69 6f 6e 2e 43 68 61 72 74 69 6e 67 } //1 System.Windows.Forms.DataVisualization.Charting
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=16
 
}