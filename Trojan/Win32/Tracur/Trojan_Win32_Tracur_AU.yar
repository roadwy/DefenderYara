
rule Trojan_Win32_Tracur_AU{
	meta:
		description = "Trojan:Win32/Tracur.AU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {66 69 72 65 66 6f 78 [0-0a] 63 68 72 6f 6d 65 [0-0a] 69 65 78 70 6c 6f 72 65 [0-35] 73 63 6f 64 65 66 } //1
		$a_01_1 = {43 22 6b 65 79 a3 3a 07 0e 4d 49 47 66 43 41 30 } //1
		$a_01_2 = {64 6e 73 65 72 72 6f 72 64 69 61 67 6f 66 66 5f 77 65 62 6f 63 2e 68 74 6d } //1 dnserrordiagoff_weboc.htm
		$a_01_3 = {21 2f 73 65 61 72 63 68 2f 72 65 73 75 6c 74 73 2e 70 68 70 3f } //1 !/search/results.php?
		$a_01_4 = {0a 00 00 00 2f 73 65 61 72 63 68 3f 71 3d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule Trojan_Win32_Tracur_AU_2{
	meta:
		description = "Trojan:Win32/Tracur.AU,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc8 00 01 00 7d 00 00 "
		
	strings :
		$a_01_0 = {00 00 00 62 64 70 63 65 6a 74 7a 2e 64 6c 6c 00 } //1
		$a_01_1 = {00 00 00 62 64 73 6e 65 7a 71 62 2e 64 6c 6c 00 } //1
		$a_01_2 = {00 00 00 62 64 78 76 61 63 64 6a 2e 64 6c 6c 00 } //1
		$a_01_3 = {00 00 00 62 72 74 70 75 66 66 72 2e 64 6c 6c 00 } //1
		$a_01_4 = {00 00 00 62 73 76 72 69 70 77 68 2e 64 6c 6c 00 } //1
		$a_01_5 = {00 00 00 62 73 78 63 61 6b 70 66 2e 64 6c 6c 00 } //1
		$a_01_6 = {00 00 00 63 63 67 74 6f 6c 6d 73 2e 64 6c 6c 00 } //1
		$a_01_7 = {00 00 00 63 6a 6e 77 75 6d 6b 6d 2e 64 6c 6c 00 } //1
		$a_01_8 = {00 00 00 63 6a 70 64 65 71 67 66 2e 64 6c 6c 00 } //1
		$a_01_9 = {00 00 00 63 70 70 74 69 64 73 6d 2e 64 6c 6c 00 } //1
		$a_01_10 = {00 00 00 63 71 68 72 75 64 74 6e 6a 2e 64 6c 6c 00 } //1
		$a_01_11 = {00 00 00 63 72 70 77 69 74 67 6e 2e 64 6c 6c 00 } //1
		$a_01_12 = {00 00 00 63 73 64 67 6f 6e 73 67 2e 64 6c 6c 00 } //1
		$a_01_13 = {00 00 00 63 74 7a 6c 69 64 77 72 2e 64 6c 6c 00 } //1
		$a_01_14 = {00 00 00 63 77 73 66 69 7a 64 73 2e 64 6c 6c 00 } //1
		$a_01_15 = {00 00 00 63 77 78 6e 79 6c 68 7a 2e 64 6c 6c 00 } //1
		$a_01_16 = {00 00 00 63 78 6b 77 75 6e 6c 74 2e 64 6c 6c 00 } //1
		$a_01_17 = {00 00 00 64 62 65 78 70 69 64 61 2e 64 6c 6c 00 } //1
		$a_01_18 = {00 00 00 64 64 6c 77 75 62 78 70 2e 64 6c 6c 00 } //1
		$a_01_19 = {00 00 00 64 67 64 73 65 6a 67 64 2e 64 6c 6c 00 } //1
		$a_01_20 = {00 00 00 64 68 67 71 79 68 7a 78 2e 64 6c 6c 00 } //1
		$a_01_21 = {00 00 00 64 6e 7a 70 75 6d 78 7a 2e 64 6c 6c 00 } //1
		$a_01_22 = {00 00 00 65 70 30 6c 76 72 31 35 2e 64 6c 6c 00 } //1
		$a_01_23 = {00 00 00 66 64 73 77 61 62 76 70 2e 64 6c 6c 00 } //1
		$a_01_24 = {00 00 00 66 6c 63 6b 6f 6e 66 64 2e 64 6c 6c 00 } //1
		$a_01_25 = {00 00 00 66 6d 74 6b 61 64 62 77 2e 64 6c 6c 00 } //1
		$a_01_26 = {00 00 00 66 73 77 63 75 78 71 7a 2e 64 6c 6c 00 } //1
		$a_01_27 = {00 00 00 67 70 62 6d 79 6c 64 6a 2e 64 6c 6c 00 } //1
		$a_01_28 = {00 00 00 68 64 70 7a 6f 63 72 73 2e 64 6c 6c 00 } //1
		$a_01_29 = {00 00 00 68 6b 6c 70 65 6e 76 6d 2e 64 6c 6c 00 } //1
		$a_01_30 = {00 00 00 68 6c 68 6c 65 74 72 67 2e 64 6c 6c 00 } //1
		$a_01_31 = {00 00 00 68 71 6c 78 75 76 70 7a 2e 64 6c 6c 00 } //1
		$a_01_32 = {00 00 00 68 71 70 67 61 6b 6b 7a 2e 64 6c 6c 00 } //1
		$a_01_33 = {00 00 00 68 72 71 77 69 6d 64 63 2e 64 6c 6c 00 } //1
		$a_01_34 = {00 00 00 68 78 76 64 69 77 63 76 2e 64 6c 6c 00 } //1
		$a_01_35 = {00 00 00 6a 66 70 78 6f 63 70 6a 2e 64 6c 6c 00 } //1
		$a_01_36 = {00 00 00 6a 68 72 64 6f 63 68 72 2e 64 6c 6c 00 } //1
		$a_01_37 = {00 00 00 6a 68 77 77 61 6e 67 6e 2e 64 6c 6c 00 } //1
		$a_01_38 = {00 00 00 6a 6c 64 78 75 71 6d 71 2e 64 6c 6c 00 } //1
		$a_01_39 = {00 00 00 6a 6c 6d 67 65 7a 6d 6b 2e 64 6c 6c 00 } //1
		$a_01_40 = {00 00 00 6a 72 71 6c 6f 70 7a 70 2e 64 6c 6c 00 } //1
		$a_01_41 = {00 00 00 6b 64 71 64 75 70 6d 66 2e 64 6c 6c 00 } //1
		$a_01_42 = {00 00 00 6b 66 78 70 61 6a 67 64 2e 64 6c 6c 00 } //1
		$a_01_43 = {00 00 00 6b 6c 77 72 75 71 7a 64 2e 64 6c 6c 00 } //1
		$a_01_44 = {00 00 00 6b 73 64 76 69 71 6b 6d 2e 64 6c 6c 00 } //1
		$a_01_45 = {00 00 00 6b 76 70 73 75 67 64 70 2e 64 6c 6c 00 } //1
		$a_01_46 = {00 00 00 6b 77 72 6b 6f 66 78 68 2e 64 6c 6c 00 } //1
		$a_01_47 = {00 00 00 6c 62 68 71 79 72 6c 7a 2e 64 6c 6c 00 } //1
		$a_01_48 = {00 00 00 6c 68 78 68 6f 73 6a 77 2e 64 6c 6c 00 } //1
		$a_01_49 = {00 00 00 6c 6d 66 70 79 63 6c 68 2e 64 6c 6c 00 } //1
		$a_01_50 = {00 00 00 6c 6d 6b 73 75 78 77 76 2e 64 6c 6c 00 } //1
		$a_01_51 = {00 00 00 6c 77 62 71 6f 6d 67 70 2e 64 6c 6c 00 } //1
		$a_01_52 = {00 00 00 6c 7a 74 70 75 7a 64 68 2e 64 6c 6c 00 } //1
		$a_01_53 = {00 00 00 6d 64 73 6c 65 76 6a 72 2e 64 6c 6c 00 } //1
		$a_01_54 = {00 00 00 6d 6c 63 77 61 72 6c 6d 2e 64 6c 6c 00 } //1
		$a_01_55 = {00 00 00 6d 6c 67 68 75 70 67 62 2e 64 6c 6c 00 } //1
		$a_01_56 = {00 00 00 6d 6c 67 72 6f 71 63 67 2e 64 6c 6c 00 } //1
		$a_01_57 = {00 00 00 6d 71 76 6b 6f 64 78 76 2e 64 6c 6c 00 } //1
		$a_01_58 = {00 00 00 6e 62 70 6c 69 6b 70 76 2e 64 6c 6c 00 } //1
		$a_01_59 = {00 00 00 6e 6a 77 76 65 71 68 68 2e 64 6c 6c 00 } //1
		$a_01_60 = {00 00 00 6e 70 74 77 65 71 62 73 2e 64 6c 6c 00 } //1
		$a_01_61 = {00 00 00 6e 72 70 64 61 6b 7a 63 2e 64 6c 6c 00 } //1
		$a_01_62 = {00 00 00 6e 73 62 6e 69 6b 68 6e 2e 64 6c 6c 00 } //1
		$a_01_63 = {00 00 00 6e 7a 63 68 65 68 6d 7a 6a 6f 2e 64 6c 6c 00 } //1
		$a_01_64 = {00 00 00 70 62 78 77 61 74 6c 7a 2e 64 6c 6c 00 } //1
		$a_01_65 = {00 00 00 70 66 6d 62 6f 63 62 6a 2e 64 6c 6c 00 } //1
		$a_01_66 = {00 00 00 70 68 71 6e 61 76 77 66 2e 64 6c 6c 00 } //1
		$a_01_67 = {00 00 00 70 6d 6c 72 75 71 71 70 2e 64 6c 6c 00 } //1
		$a_01_68 = {00 00 00 70 6e 6b 70 69 63 6a 68 2e 64 6c 6c 00 } //1
		$a_01_69 = {00 00 00 71 62 71 6d 6f 6a 77 64 2e 64 6c 6c 00 } //1
		$a_01_70 = {00 00 00 71 63 67 64 61 6d 76 6b 2e 64 6c 6c 00 } //1
		$a_01_71 = {00 00 00 71 64 62 62 6f 73 64 64 2e 64 6c 6c 00 } //1
		$a_01_72 = {00 00 00 71 6d 77 77 79 62 63 74 2e 64 6c 6c 00 } //1
		$a_01_73 = {00 00 00 71 6e 76 6c 61 62 63 71 2e 64 6c 6c 00 } //1
		$a_01_74 = {00 00 00 71 73 64 76 6f 76 6e 74 2e 64 6c 6c 00 } //1
		$a_01_75 = {00 00 00 71 76 76 6d 61 6d 76 6b 2e 64 6c 6c 00 } //1
		$a_01_76 = {00 00 00 71 78 6c 74 79 71 68 6b 2e 64 6c 6c 00 } //1
		$a_01_77 = {00 00 00 71 78 72 6a 79 78 64 68 2e 64 6c 6c 00 } //1
		$a_01_78 = {00 00 00 72 62 68 63 61 71 6b 68 2e 64 6c 6c 00 } //1
		$a_01_79 = {00 00 00 72 62 6c 70 79 73 72 76 2e 64 6c 6c 00 } //1
		$a_01_80 = {00 00 00 72 62 73 68 6f 74 6a 2e 64 6c 6c 00 } //1
		$a_01_81 = {00 00 00 72 66 73 6c 64 2e 64 6c 6c 00 } //1
		$a_01_82 = {00 00 00 72 66 76 6b 69 78 6d 7a 2e 64 6c 6c 00 } //1
		$a_01_83 = {00 00 00 72 6d 78 71 61 6c 7a 76 2e 64 6c 6c 00 } //1
		$a_01_84 = {00 00 00 72 71 67 6d 69 62 7a 6e 2e 64 6c 6c 00 } //1
		$a_01_85 = {00 00 00 72 72 6a 63 61 6a 74 7a 2e 64 6c 6c 00 } //1
		$a_01_86 = {00 00 00 72 72 77 6a 79 66 6a 66 2e 64 6c 6c 00 } //1
		$a_01_87 = {00 00 00 72 76 77 70 69 6e 67 67 2e 64 6c 6c 00 } //1
		$a_01_88 = {00 00 00 72 77 6c 74 6f 68 71 62 2e 64 6c 6c 00 } //1
		$a_01_89 = {00 00 00 73 6a 71 67 79 67 68 71 2e 64 6c 6c 00 } //1
		$a_01_90 = {00 00 00 73 6b 7a 62 65 6b 62 6e 2e 64 6c 6c 00 } //1
		$a_01_91 = {00 00 00 73 6c 64 64 69 73 73 65 63 74 65 72 2e 64 6c 6c 00 } //1
		$a_01_92 = {00 00 00 73 71 62 71 61 7a 63 6d 2e 64 6c 6c 00 } //1
		$a_01_93 = {00 00 00 73 72 73 63 61 6c 65 72 2e 64 6c 6c 00 } //1
		$a_01_94 = {00 00 00 74 64 72 6c 6f 71 68 73 2e 64 6c 6c 00 } //1
		$a_01_95 = {00 00 00 74 67 62 70 6f 6a 70 64 2e 64 6c 6c 00 } //1
		$a_01_96 = {00 00 00 74 70 76 70 79 7a 68 72 2e 64 6c 6c 00 } //1
		$a_01_97 = {00 00 00 74 7a 73 68 65 72 78 73 2e 64 6c 6c 00 } //1
		$a_01_98 = {00 00 00 75 72 62 7a 79 6a 6e 66 2e 64 6c 6c 00 } //1
		$a_01_99 = {00 00 00 76 64 67 72 61 62 76 6a 2e 64 6c 6c 00 } //1
		$a_01_100 = {00 00 00 76 64 74 73 61 63 7a 77 2e 64 6c 6c 00 } //1
		$a_01_101 = {00 00 00 76 6a 62 70 6f 77 6b 68 2e 64 6c 6c 00 } //1
		$a_01_102 = {00 00 00 76 6e 62 6d 69 74 72 6c 2e 64 6c 6c 00 } //1
		$a_01_103 = {00 00 00 76 72 63 74 69 74 67 78 2e 64 6c 6c 00 } //1
		$a_01_104 = {00 00 00 76 73 72 64 79 68 6e 7a 2e 64 6c 6c 00 } //1
		$a_01_105 = {00 00 00 76 78 64 72 6f 71 6c 64 2e 64 6c 6c 00 } //1
		$a_01_106 = {00 00 00 77 67 68 64 61 63 70 63 2e 64 6c 6c 00 } //1
		$a_01_107 = {00 00 00 77 6b 6a 78 65 63 76 76 2e 64 6c 6c 00 } //1
		$a_01_108 = {00 00 00 77 71 6d 73 65 62 67 63 2e 64 6c 6c 00 } //1
		$a_01_109 = {00 00 00 77 71 74 7a 6f 6b 72 74 2e 64 6c 6c 00 } //1
		$a_01_110 = {00 00 00 77 77 71 62 69 66 6e 78 2e 64 6c 6c 00 } //1
		$a_01_111 = {00 00 00 78 6e 62 6a 61 73 72 70 2e 64 6c 6c 00 } //1
		$a_01_112 = {00 00 00 78 72 78 6e 75 69 2e 64 6c 6c 00 } //1
		$a_01_113 = {00 00 00 78 78 71 67 79 6e 64 70 2e 64 6c 6c 00 } //1
		$a_01_114 = {00 00 00 78 7a 73 6b 69 67 6d 74 2e 64 6c 6c 00 } //1
		$a_01_115 = {00 00 00 7a 62 6b 6d 79 6d 62 62 2e 64 6c 6c 00 } //1
		$a_01_116 = {00 00 00 7a 66 64 63 79 6e 62 7a 2e 64 6c 6c 00 } //1
		$a_01_117 = {00 00 00 7a 6a 78 63 75 64 6a 7a 2e 64 6c 6c 00 } //1
		$a_01_118 = {00 00 00 7a 6b 63 77 6f 6b 74 7a 2e 64 6c 6c 00 } //1
		$a_01_119 = {00 00 00 7a 6d 6b 62 79 67 6e 7a 2e 64 6c 6c 00 } //1
		$a_01_120 = {00 00 00 7a 6d 6b 64 79 73 68 63 2e 64 6c 6c 00 } //1
		$a_01_121 = {00 00 00 7a 70 64 72 79 77 67 64 2e 64 6c 6c 00 } //1
		$a_01_122 = {00 00 00 7a 76 63 76 6f 76 74 62 2e 64 6c 6c 00 } //1
		$a_01_123 = {00 00 00 78 70 6d 70 61 6d 62 6c 2e 64 6c 6c 00 } //1
		$a_01_124 = {00 00 00 6d 71 72 68 69 67 67 6d 2e 64 6c 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1+(#a_01_26  & 1)*1+(#a_01_27  & 1)*1+(#a_01_28  & 1)*1+(#a_01_29  & 1)*1+(#a_01_30  & 1)*1+(#a_01_31  & 1)*1+(#a_01_32  & 1)*1+(#a_01_33  & 1)*1+(#a_01_34  & 1)*1+(#a_01_35  & 1)*1+(#a_01_36  & 1)*1+(#a_01_37  & 1)*1+(#a_01_38  & 1)*1+(#a_01_39  & 1)*1+(#a_01_40  & 1)*1+(#a_01_41  & 1)*1+(#a_01_42  & 1)*1+(#a_01_43  & 1)*1+(#a_01_44  & 1)*1+(#a_01_45  & 1)*1+(#a_01_46  & 1)*1+(#a_01_47  & 1)*1+(#a_01_48  & 1)*1+(#a_01_49  & 1)*1+(#a_01_50  & 1)*1+(#a_01_51  & 1)*1+(#a_01_52  & 1)*1+(#a_01_53  & 1)*1+(#a_01_54  & 1)*1+(#a_01_55  & 1)*1+(#a_01_56  & 1)*1+(#a_01_57  & 1)*1+(#a_01_58  & 1)*1+(#a_01_59  & 1)*1+(#a_01_60  & 1)*1+(#a_01_61  & 1)*1+(#a_01_62  & 1)*1+(#a_01_63  & 1)*1+(#a_01_64  & 1)*1+(#a_01_65  & 1)*1+(#a_01_66  & 1)*1+(#a_01_67  & 1)*1+(#a_01_68  & 1)*1+(#a_01_69  & 1)*1+(#a_01_70  & 1)*1+(#a_01_71  & 1)*1+(#a_01_72  & 1)*1+(#a_01_73  & 1)*1+(#a_01_74  & 1)*1+(#a_01_75  & 1)*1+(#a_01_76  & 1)*1+(#a_01_77  & 1)*1+(#a_01_78  & 1)*1+(#a_01_79  & 1)*1+(#a_01_80  & 1)*1+(#a_01_81  & 1)*1+(#a_01_82  & 1)*1+(#a_01_83  & 1)*1+(#a_01_84  & 1)*1+(#a_01_85  & 1)*1+(#a_01_86  & 1)*1+(#a_01_87  & 1)*1+(#a_01_88  & 1)*1+(#a_01_89  & 1)*1+(#a_01_90  & 1)*1+(#a_01_91  & 1)*1+(#a_01_92  & 1)*1+(#a_01_93  & 1)*1+(#a_01_94  & 1)*1+(#a_01_95  & 1)*1+(#a_01_96  & 1)*1+(#a_01_97  & 1)*1+(#a_01_98  & 1)*1+(#a_01_99  & 1)*1+(#a_01_100  & 1)*1+(#a_01_101  & 1)*1+(#a_01_102  & 1)*1+(#a_01_103  & 1)*1+(#a_01_104  & 1)*1+(#a_01_105  & 1)*1+(#a_01_106  & 1)*1+(#a_01_107  & 1)*1+(#a_01_108  & 1)*1+(#a_01_109  & 1)*1+(#a_01_110  & 1)*1+(#a_01_111  & 1)*1+(#a_01_112  & 1)*1+(#a_01_113  & 1)*1+(#a_01_114  & 1)*1+(#a_01_115  & 1)*1+(#a_01_116  & 1)*1+(#a_01_117  & 1)*1+(#a_01_118  & 1)*1+(#a_01_119  & 1)*1+(#a_01_120  & 1)*1+(#a_01_121  & 1)*1+(#a_01_122  & 1)*1+(#a_01_123  & 1)*1+(#a_01_124  & 1)*1) >=1
 
}