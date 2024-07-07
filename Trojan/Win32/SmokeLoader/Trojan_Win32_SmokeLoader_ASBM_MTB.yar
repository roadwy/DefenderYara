
rule Trojan_Win32_SmokeLoader_ASBM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ASBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0f 00 00 "
		
	strings :
		$a_01_0 = {77 69 6a 69 77 75 66 65 72 75 77 61 6e 61 72 61 68 75 70 20 66 65 66 6f 6e 6f 70 6f 68 6f 78 6f 63 75 67 69 68 61 70 6f 72 65 6d 6f 66 6f 6c 75 6c } //1 wijiwuferuwanarahup fefonopohoxocugihaporemofolul
		$a_01_1 = {73 61 76 65 72 69 77 69 79 20 64 61 70 65 74 61 62 65 63 61 62 65 64 75 68 6f 6b 61 73 20 62 75 79 20 6c 65 78 6f 67 61 6e 6f 6d 61 6b 61 66 61 6c 75 77 61 78 75 72 75 72 69 6d 61 6d 75 64 20 66 6f 62 6f 77 69 72 69 6b 65 70 6f 6e 61 6e 69 73 65 77 69 7a 75 } //1 saveriwiy dapetabecabeduhokas buy lexoganomakafaluwaxururimamud fobowirikeponanisewizu
		$a_01_2 = {72 75 72 6f 74 6f 76 75 76 65 79 75 68 61 6a 65 78 6f 73 75 66 61 63 75 6a 61 } //1 rurotovuveyuhajexosufacuja
		$a_01_3 = {67 65 76 69 68 69 79 65 72 75 64 75 67 69 63 65 77 65 64 69 67 75 63 69 62 6f 64 61 70 75 77 20 6e 6f 72 } //1 gevihiyerudugicewedigucibodapuw nor
		$a_01_4 = {6c 6f 73 61 77 61 6c 75 66 65 79 75 64 69 72 69 73 69 72 61 70 69 68 69 70 6f 73 69 62 75 } //1 losawalufeyudirisirapihiposibu
		$a_01_5 = {72 6f 77 6f 6c 6f 6d 6f 73 61 66 61 72 6f 67 65 73 75 6e 65 62 75 6e 69 7a 75 73 61 6b 69 6e 20 73 69 63 69 6a 75 } //1 rowolomosafarogesunebunizusakin siciju
		$a_01_6 = {72 6f 76 69 6b 6f 76 61 70 69 7a 69 20 6b 65 63 6f 7a 65 63 69 63 65 7a 75 67 61 76 6f 79 20 6b 69 64 6f 76 75 62 6f 74 69 6d 6f 79 69 6b 75 20 73 69 72 69 6b 69 73 61 79 69 68 75 74 75 7a } //1 rovikovapizi kecozecicezugavoy kidovubotimoyiku sirikisayihutuz
		$a_01_7 = {72 69 62 69 6d 69 67 65 63 61 20 63 61 72 6f 73 75 6a 75 77 6f 70 6f 73 65 67 65 67 65 76 69 64 69 78 20 6c 6f 6b 75 76 69 63 75 79 65 63 75 68 69 67 61 6c 75 6d 69 79 61 64 65 70 65 20 78 75 6c 61 68 6f 79 6f 6d 61 20 77 65 67 75 73 65 68 6f 73 } //1 ribimigeca carosujuwoposegegevidix lokuvicuyecuhigalumiyadepe xulahoyoma wegusehos
		$a_01_8 = {64 61 62 61 76 69 73 6f 6c 61 79 69 78 6f 66 61 6e 65 64 61 73 65 63 69 6c 69 68 6f 6a 6f } //1 dabavisolayixofanedasecilihojo
		$a_01_9 = {77 69 7a 61 73 6f 66 75 70 69 76 75 73 6f 63 75 73 6f 77 75 70 75 70 61 76 6f 78 75 72 75 67 } //1 wizasofupivusocusowupupavoxurug
		$a_01_10 = {77 75 79 65 76 75 73 6f 63 6f 63 65 6b 6f 70 20 7a 65 67 6f 66 75 64 65 67 65 77 69 6b 65 7a 69 76 69 73 61 68 69 74 61 74 65 6a 75 68 65 6a } //1 wuyevusococekop zegofudegewikezivisahitatejuhej
		$a_01_11 = {7a 75 77 75 6d 6f 78 75 63 69 72 6f 6e 65 76 61 78 75 79 } //1 zuwumoxucironevaxuy
		$a_01_12 = {62 69 76 61 76 75 76 75 66 75 6b 6f 76 75 6e 75 72 6f 63 6f 74 65 78 75 73 75 20 74 69 73 61 7a 6f 6c 61 6b 61 6e 65 76 75 6a 69 20 6a 75 66 6f 6e 6f 6a 69 6a 61 73 69 77 61 72 65 6d 61 77 6f 70 65 67 6f 72 } //1 bivavuvufukovunurocotexusu tisazolakanevuji jufonojijasiwaremawopegor
		$a_01_13 = {66 75 77 65 78 6f 72 6f 76 75 76 69 76 69 64 65 6e 65 76 20 73 6f 79 61 76 65 77 69 73 69 79 75 6e 61 77 69 62 65 68 69 79 61 6a 20 68 61 6e 75 76 69 6d 61 68 61 6e 6f 6c 69 74 6f 6e 65 79 75 79 20 73 75 77 6f 70 69 6a 6f 77 } //1 fuwexorovuvividenev soyavewisiyunawibehiyaj hanuvimahanolitoneyuy suwopijow
		$a_01_14 = {78 69 63 69 68 75 63 75 6a 69 68 61 74 69 77 6f 6d 69 68 61 7a 75 79 20 77 75 73 75 63 65 68 61 64 65 62 69 77 65 76 69 7a 65 72 6f 78 6f 78 65 6c 69 76 75 } //1 xicihucujihatiwomihazuy wusucehadebiwevizeroxoxelivu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=5
 
}