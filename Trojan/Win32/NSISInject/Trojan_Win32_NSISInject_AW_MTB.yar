
rule Trojan_Win32_NSISInject_AW_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 61 72 69 73 74 68 6d 69 63 5c 53 70 65 65 64 6f 6d 65 74 65 72 65 74 73 31 31 39 2e 46 61 63 } //1 Paristhmic\Speedometerets119.Fac
		$a_01_1 = {53 68 65 6c 74 61 73 5c 41 66 72 65 67 6e 69 6e 67 73 70 72 69 73 65 72 2e 69 6e 69 } //1 Sheltas\Afregningspriser.ini
		$a_01_2 = {46 72 61 6e 6b 61 62 6c 65 5c 41 6e 6b 65 72 67 61 6e 67 73 5c 55 6e 68 6f 72 6f 73 63 6f 70 69 63 5c 43 72 61 79 6f 6e 69 73 74 2e 50 72 6f } //1 Frankable\Ankergangs\Unhoroscopic\Crayonist.Pro
		$a_01_3 = {53 74 69 6c 6c 65 6b 6e 61 70 73 31 33 33 5c 55 6e 64 65 72 76 69 73 6e 69 6e 67 73 70 6c 69 67 74 65 72 6e 65 73 5c 46 6f 72 73 74 61 6e 64 65 72 69 6e 64 65 72 6e 65 73 5c 43 61 72 70 69 } //1 Stilleknaps133\Undervisningspligternes\Forstanderindernes\Carpi
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 76 61 72 65 66 6f 72 64 65 6c 69 6e 67 65 72 5c 57 6f 6d 61 6e 68 6f 6f 64 } //1 Software\varefordelinger\Womanhood
		$a_01_5 = {4c 61 6e 64 65 76 65 6a 65 25 5c 43 69 72 63 65 2e 59 6f 75 } //1 Landeveje%\Circe.You
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}