
rule Trojan_O97M_EncDoc_SBR_MSR{
	meta:
		description = "Trojan:O97M/EncDoc.SBR!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 62 6c 75 65 73 74 65 65 6c 65 6e 65 72 67 79 2e 63 6f 6d 2f 64 65 72 74 6f 6e 2f 65 6e 65 72 67 79 2e 70 68 70 } //1 https://bluesteelenergy.com/derton/energy.php
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 64 72 6d 61 72 69 65 70 61 70 70 61 73 2e 63 6f 6d 2f 64 72 70 65 70 70 65 72 2f 63 6f 6c 61 64 61 73 2e 70 68 70 } //1 https://drmariepappas.com/drpepper/coladas.php
		$a_00_2 = {68 74 74 70 73 3a 2f 2f 77 6f 6f 64 65 6e 72 65 73 74 6f 72 61 74 69 6f 6e 73 2e 63 6f 6d 2f 67 65 72 6e 61 65 72 2f 77 6f 6f 64 6c 65 73 2e 70 68 70 } //1 https://woodenrestorations.com/gernaer/woodles.php
		$a_00_3 = {7a 69 70 66 6c 64 72 } //1 zipfldr
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}