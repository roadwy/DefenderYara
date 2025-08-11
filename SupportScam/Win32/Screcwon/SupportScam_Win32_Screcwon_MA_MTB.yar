
rule SupportScam_Win32_Screcwon_MA_MTB{
	meta:
		description = "SupportScam:Win32/Screcwon.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 15 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 6a 6d 6f 72 67 61 6e 5c 53 6f 75 72 63 65 5c 63 77 63 6f 6e 74 72 6f 6c 5c 4d 69 73 63 5c 42 6f 6f 74 73 74 72 61 70 70 65 72 5c 52 65 6c 65 61 73 65 5c 43 6c 69 63 6b 4f 6e 63 65 52 75 6e 6e 65 72 2e 70 64 62 } //20 C:\Users\jmorgan\Source\cwcontrol\Misc\Bootstrapper\Release\ClickOnceRunner.pdb
		$a_81_1 = {43 3a 5c 55 73 65 72 73 5c 6a 6d 6f 72 67 61 6e 5c 53 6f 75 72 63 65 5c 63 77 63 6f 6e 74 72 6f 6c 5c 43 75 73 74 6f 6d 5c 44 6f 74 4e 65 74 52 75 6e 6e 65 72 5c 52 65 6c 65 61 73 65 5c 44 6f 74 4e 65 74 52 75 6e 6e 65 72 2e 70 64 62 } //20 C:\Users\jmorgan\Source\cwcontrol\Custom\DotNetRunner\Release\DotNetRunner.pdb
		$a_81_2 = {2e 74 6f 70 } //1 .top
		$a_81_3 = {2e 69 6e 6e 6f 63 72 65 65 64 2e 63 6f 6d } //1 .innocreed.com
		$a_81_4 = {2e 63 6f 6e 74 72 6f 6c 68 75 62 2e 65 73 } //1 .controlhub.es
		$a_81_5 = {2e 72 61 74 6f 73 63 72 65 65 6e 63 6f 2e 63 6f 6d } //1 .ratoscreenco.com
		$a_81_6 = {2e 73 63 72 65 65 6e 73 63 6f 6e 6e 65 63 74 70 72 6f 2e 63 6f 6d } //1 .screensconnectpro.com
		$a_81_7 = {73 6c 70 6c 65 67 61 6c 66 69 6e 61 6e 63 65 2e 63 6f 6d } //1 slplegalfinance.com
		$a_81_8 = {2e 66 69 6c 65 73 64 6f 6e 77 6c 6f 61 64 73 2e 63 6f 6d } //1 .filesdonwloads.com
		$a_81_9 = {77 69 7a 7a 2e 69 6e 66 69 6e 69 74 79 63 6c 6f 75 64 2e 6f 72 67 } //1 wizz.infinitycloud.org
		$a_81_10 = {6c 6c 6b 74 35 30 31 2e 64 64 6e 73 2e 6e 65 74 } //1 llkt501.ddns.net
		$a_81_11 = {79 6f 75 72 72 6c 64 6e 73 32 32 2e 68 6f 70 74 6f 2e 6f 72 67 } //1 yourrldns22.hopto.org
		$a_81_12 = {77 6b 33 36 62 61 63 6b 39 36 36 2e 73 69 74 65 } //1 wk36back966.site
		$a_81_13 = {76 6f 69 64 2e 63 6f 72 73 61 7a 6f 6e 65 2e 63 6f 6d } //1 void.corsazone.com
		$a_81_14 = {72 65 6c 61 79 2e 7a 69 61 64 70 61 6e 65 65 6c 2e 63 6f 6d } //1 relay.ziadpaneel.com
		$a_81_15 = {6d 61 69 6c 2e 73 65 63 75 72 65 64 6f 63 75 6d 65 6e 74 66 69 6c 65 64 6f 77 6e 6c 6f 61 64 2e 63 6f 6d } //1 mail.securedocumentfiledownload.com
		$a_81_16 = {64 75 61 6c 2e 73 61 6c 74 75 74 61 2e 63 6f 6d } //1 dual.saltuta.com
		$a_81_17 = {2e 6f 72 67 61 6e 7a 6f 70 65 72 61 74 65 2e 63 6f 6d } //1 .organzoperate.com
		$a_81_18 = {2e 65 70 68 65 6c 70 2e 73 69 74 65 } //1 .ephelp.site
		$a_81_19 = {64 63 6f 6e 74 72 6f 6c 2e 67 75 69 64 7a 69 6e 2e 63 6f 6d } //1 dcontrol.guidzin.com
		$a_81_20 = {64 6f 63 73 2e 76 69 65 77 79 6f 75 72 73 74 61 74 65 6d 65 6e 74 6f 6e 6c 69 6e 65 2e 63 6f 6d } //1 docs.viewyourstatementonline.com
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1+(#a_81_17  & 1)*1+(#a_81_18  & 1)*1+(#a_81_19  & 1)*1+(#a_81_20  & 1)*1) >=21
 
}